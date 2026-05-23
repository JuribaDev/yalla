package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/JuribaDev/yalla/internal/controlplane/apienvelope"
	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
	"github.com/JuribaDev/yalla/internal/controlplane/backoffice"
	"github.com/JuribaDev/yalla/internal/controlplane/policy"
	"github.com/JuribaDev/yalla/internal/controlplane/store"
	"github.com/JuribaDev/yalla/internal/controlplane/telemetry"
	"github.com/JuribaDev/yalla/internal/controlplane/validate"
)

var errNoAdminConfigDryRunner = errors.New("httpapi: no admin config dry-run validator configured")
var errNoAdminConfigPromotionManager = errors.New("httpapi: no admin config promotion manager configured")

// AdminConfigDryRunner validates candidate backoffice runtime configuration
// before publish. It is deliberately narrower than the concrete backoffice
// validator so the HTTP layer owns only request/response mapping.
type AdminConfigDryRunner interface {
	Validate(ctx context.Context, in backoffice.DryRunInput) (backoffice.DryRunResult, error)
}

// AdminConfigPromotionManager owns backoffice config export/import workflows.
type AdminConfigPromotionManager interface {
	Export(ctx context.Context, in store.AdminConfigExportInput, auditCtx store.AdminConfigAuditContext) (store.AdminConfigExportManifest, error)
	Import(ctx context.Context, in store.AdminConfigImportInput, auditCtx store.AdminConfigAuditContext) (store.AdminConfigImportReport, error)
}

type adminConfigDryRunRequestBody struct {
	ConfigSetID             string                  `json:"config_set_id,omitempty"`
	Domain                  store.AdminConfigDomain `json:"domain"`
	Payload                 map[string]any          `json:"payload"`
	SimulateOrganizationIDs []string                `json:"simulate_organization_ids,omitempty"`
}

type adminConfigImportRequestBody struct {
	TargetEnvironment   string                          `json:"target_environment"`
	Manifest            store.AdminConfigExportManifest `json:"manifest"`
	DryRun              bool                            `json:"dry_run"`
	AvailableSecretRefs []string                        `json:"available_secret_refs,omitempty"`
	AllowDowngrade      bool                            `json:"allow_downgrade,omitempty"`
}

func dryRunAdminConfigHandler(runner AdminConfigDryRunner) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if runner == nil {
			apienvelope.WriteError(w, requestID(r), apierr.Internal(errNoAdminConfigDryRunner))
			return
		}
		var body adminConfigDryRunRequestBody
		if err := validate.DecodeJSON(r.Body, &body, 0); err != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(err))
			return
		}
		payload, err := marshalAdminConfigPayload(body.Payload)
		if err != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(err))
			return
		}
		result, err := runner.Validate(r.Context(), backoffice.DryRunInput{
			ConfigSetID:             body.ConfigSetID,
			Domain:                  body.Domain,
			Payload:                 payload,
			SimulateOrganizationIDs: body.SimulateOrganizationIDs,
		})
		if err != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(err))
			return
		}
		if result.Warnings == nil {
			result.Warnings = []backoffice.Issue{}
		}
		if result.BlockingErrors == nil {
			result.BlockingErrors = []backoffice.Issue{}
		}
		if result.SimulatedOrganizations == nil {
			result.SimulatedOrganizations = []backoffice.OrganizationImpact{}
		}
		apienvelope.WriteData(w, http.StatusOK, requestID(r), result)
	}
}

func exportAdminConfigHandler(manager AdminConfigPromotionManager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if manager == nil {
			apienvelope.WriteError(w, requestID(r), apierr.Internal(errNoAdminConfigPromotionManager))
			return
		}
		auditCtx, err := adminConfigAuditContext(r)
		if err != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(err))
			return
		}
		manifest, err := manager.Export(r.Context(), store.AdminConfigExportInput{
			SourceEnvironment: r.URL.Query().Get("source_environment"),
		}, auditCtx)
		if err != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(err))
			return
		}
		apienvelope.WriteData(w, http.StatusOK, requestID(r), manifest)
	}
}

func importAdminConfigHandler(manager AdminConfigPromotionManager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if manager == nil {
			apienvelope.WriteError(w, requestID(r), apierr.Internal(errNoAdminConfigPromotionManager))
			return
		}
		var body adminConfigImportRequestBody
		if err := validate.DecodeJSON(r.Body, &body, 0); err != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(err))
			return
		}
		auditCtx, err := adminConfigAuditContext(r)
		if err != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(err))
			return
		}
		report, err := manager.Import(r.Context(), store.AdminConfigImportInput{
			TargetEnvironment:   body.TargetEnvironment,
			Manifest:            body.Manifest,
			DryRun:              body.DryRun,
			AvailableSecretRefs: body.AvailableSecretRefs,
			AllowDowngrade:      body.AllowDowngrade,
		}, auditCtx)
		if err != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(err))
			return
		}
		apienvelope.WriteData(w, http.StatusOK, requestID(r), report)
	}
}

func marshalAdminConfigPayload(payload map[string]any) ([]byte, error) {
	if payload == nil {
		return []byte(`{}`), nil
	}
	out, err := json.Marshal(payload)
	if err != nil {
		return nil, apierr.InvalidInput(apierr.FieldViolation{Field: "payload", Reason: "must be valid JSON"})
	}
	return out, nil
}

func adminConfigAuditContext(r *http.Request) (store.AdminConfigAuditContext, error) {
	principal, ok := policy.PrincipalFromContext(r.Context())
	if !ok || principal.ID == "" || principal.OrganizationID == "" {
		return store.AdminConfigAuditContext{}, apierr.Unauthenticated("admin config operation requires an authenticated principal")
	}
	return store.AdminConfigAuditContext{
		ActorOrgID:    principal.OrganizationID,
		ActorID:       principal.ID,
		ActorKind:     principal.Kind.String(),
		RequestID:     requestID(r),
		CorrelationID: telemetry.CorrelationID(r.Context()),
		Reason:        r.Header.Get("X-Yalla-Reason"),
	}, nil
}
