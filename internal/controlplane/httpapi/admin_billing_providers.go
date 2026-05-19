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

var errNoAdminBillingProviderManager = errors.New("httpapi: no admin billing provider manager configured")

// AdminBillingProviderUpsertInput is the validated write payload passed to the
// backoffice billing provider manager.
type AdminBillingProviderUpsertInput = store.UpsertBillingProviderInput

// AdminBillingProviderTestInput is the side-effect-free provider test input.
type AdminBillingProviderTestInput = store.BillingProviderTestInput

// AdminBillingProviderTestResult is the stable provider test result payload.
type AdminBillingProviderTestResult = store.BillingProviderTestResult

// AdminBillingProviderManager owns backoffice billing provider configuration.
type AdminBillingProviderManager interface {
	UpsertBillingProvider(ctx context.Context, key string, in AdminBillingProviderUpsertInput, auditCtx store.AdminBillingProviderAuditContext) (store.BillingProviderConfig, error)
	GetBillingProvider(ctx context.Context, key string) (store.BillingProviderConfig, error)
	TestBillingProvider(ctx context.Context, key string, in AdminBillingProviderTestInput, auditCtx store.AdminBillingProviderAuditContext) (AdminBillingProviderTestResult, error)
}

type adminBillingProviderUpsertRequestBody struct {
	ProviderType               store.BillingProviderType `json:"provider_type"`
	DisplayName                string                    `json:"display_name,omitempty"`
	SecretReference            string                    `json:"secret_reference,omitempty"`
	CredentialValue            *string                   `json:"credential_value,omitempty"`
	ExportCadenceSeconds       int                       `json:"export_cadence_seconds,omitempty"`
	RetryMaxAttempts           int                       `json:"retry_max_attempts,omitempty"`
	RetryInitialBackoffSeconds int                       `json:"retry_initial_backoff_seconds,omitempty"`
	DryRun                     bool                      `json:"dry_run"`
	Metadata                   map[string]string         `json:"metadata,omitempty"`
	Enabled                    bool                      `json:"enabled"`
}

type adminBillingProviderPayload struct {
	ID                         string            `json:"id"`
	ProviderKey                string            `json:"provider_key"`
	ProviderType               string            `json:"provider_type"`
	DisplayName                string            `json:"display_name,omitempty"`
	SecretReference            string            `json:"secret_reference,omitempty"`
	CredentialSet              bool              `json:"credential_set"`
	ExportCadenceSeconds       int               `json:"export_cadence_seconds"`
	RetryMaxAttempts           int               `json:"retry_max_attempts"`
	RetryInitialBackoffSeconds int               `json:"retry_initial_backoff_seconds"`
	DryRun                     bool              `json:"dry_run"`
	Metadata                   map[string]string `json:"metadata"`
	Enabled                    bool              `json:"enabled"`
	Revision                   int64             `json:"revision"`
	CreatedAt                  string            `json:"created_at,omitempty"`
	UpdatedAt                  string            `json:"updated_at,omitempty"`
}

func upsertAdminBillingProviderHandler(manager AdminBillingProviderManager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if manager == nil {
			apienvelope.WriteError(w, requestID(r), apierr.Internal(errNoAdminBillingProviderManager))
			return
		}
		key := strings.TrimSpace(r.PathValue("provider_key"))
		var body adminBillingProviderUpsertRequestBody
		if err := validate.DecodeJSON(r.Body, &body, 0); err != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(err))
			return
		}
		auditCtx, err := adminBillingProviderAuditContext(r)
		if err != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(err))
			return
		}
		provider, err := manager.UpsertBillingProvider(r.Context(), key, AdminBillingProviderUpsertInput{
			ProviderType:               body.ProviderType,
			DisplayName:                body.DisplayName,
			SecretReference:            body.SecretReference,
			CredentialValue:            body.CredentialValue,
			ExportCadenceSeconds:       body.ExportCadenceSeconds,
			RetryMaxAttempts:           body.RetryMaxAttempts,
			RetryInitialBackoffSeconds: body.RetryInitialBackoffSeconds,
			DryRun:                     body.DryRun,
			Metadata:                   body.Metadata,
			Enabled:                    body.Enabled,
		}, auditCtx)
		if err != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(err))
			return
		}
		apienvelope.WriteData(w, http.StatusOK, requestID(r), adminBillingProviderResponse(provider))
	}
}

func getAdminBillingProviderHandler(manager AdminBillingProviderManager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if manager == nil {
			apienvelope.WriteError(w, requestID(r), apierr.Internal(errNoAdminBillingProviderManager))
			return
		}
		key := strings.TrimSpace(r.PathValue("provider_key"))
		provider, err := manager.GetBillingProvider(r.Context(), key)
		if err != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(err))
			return
		}
		apienvelope.WriteData(w, http.StatusOK, requestID(r), adminBillingProviderResponse(provider))
	}
}

func testAdminBillingProviderHandler(manager AdminBillingProviderManager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if manager == nil {
			apienvelope.WriteError(w, requestID(r), apierr.Internal(errNoAdminBillingProviderManager))
			return
		}
		key := strings.TrimSpace(r.PathValue("provider_key"))
		var body AdminBillingProviderTestInput
		if err := validate.DecodeJSON(r.Body, &body, 0); err != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(err))
			return
		}
		auditCtx, err := adminBillingProviderAuditContext(r)
		if err != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(err))
			return
		}
		result, err := manager.TestBillingProvider(r.Context(), key, body, auditCtx)
		if err != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(err))
			return
		}
		apienvelope.WriteData(w, http.StatusOK, requestID(r), result)
	}
}

func adminBillingProviderAuditContext(r *http.Request) (store.AdminBillingProviderAuditContext, error) {
	principal, ok := policy.PrincipalFromContext(r.Context())
	if !ok || principal.ID == "" || principal.OrganizationID == "" {
		return store.AdminBillingProviderAuditContext{}, apierr.Unauthenticated("admin billing provider operation requires an authenticated principal")
	}
	return store.AdminBillingProviderAuditContext{
		ActorOrgID:    principal.OrganizationID,
		ActorID:       principal.ID,
		ActorKind:     principal.Kind.String(),
		RequestID:     telemetry.RequestID(r.Context()),
		CorrelationID: telemetry.CorrelationID(r.Context()),
		Reason:        strings.TrimSpace(r.Header.Get("X-Yalla-Reason")),
	}, nil
}

func adminBillingProviderResponse(provider store.BillingProviderConfig) adminBillingProviderPayload {
	out := adminBillingProviderPayload{
		ID:                         provider.ID,
		ProviderKey:                provider.ProviderKey,
		ProviderType:               string(provider.ProviderType),
		DisplayName:                provider.DisplayName,
		SecretReference:            provider.SecretReference,
		CredentialSet:              provider.CredentialSet,
		ExportCadenceSeconds:       provider.ExportCadenceSeconds,
		RetryMaxAttempts:           provider.RetryMaxAttempts,
		RetryInitialBackoffSeconds: provider.RetryInitialBackoffSeconds,
		DryRun:                     provider.DryRun,
		Metadata:                   provider.Metadata,
		Enabled:                    provider.Enabled,
		Revision:                   provider.Revision,
	}
	if out.Metadata == nil {
		out.Metadata = map[string]string{}
	}
	if !provider.CreatedAt.IsZero() {
		out.CreatedAt = provider.CreatedAt.UTC().Format(time.RFC3339Nano)
	}
	if !provider.UpdatedAt.IsZero() {
		out.UpdatedAt = provider.UpdatedAt.UTC().Format(time.RFC3339Nano)
	}
	return out
}
