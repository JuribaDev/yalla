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

var errNoAdminMeteringSourceManager = errors.New("httpapi: no admin metering source manager configured")

// AdminMeteringSourceUpsertInput is the validated write payload passed to the
// backoffice metering source manager.
type AdminMeteringSourceUpsertInput = store.UpsertMeteringSourceInput

// AdminMeteringSourceTestInput is the side-effect-free connection test input.
type AdminMeteringSourceTestInput = store.MeteringSourceTestInput

// AdminMeteringSourceTestResult is the stable connection test result payload.
type AdminMeteringSourceTestResult = store.MeteringSourceTestResult

// AdminMeteringSourceManager owns backoffice metering source configuration.
type AdminMeteringSourceManager interface {
	UpsertMeteringSource(ctx context.Context, key string, in AdminMeteringSourceUpsertInput, auditCtx store.AdminMeteringSourceAuditContext) (store.MeteringSource, error)
	TestMeteringSource(ctx context.Context, key string, in AdminMeteringSourceTestInput, auditCtx store.AdminMeteringSourceAuditContext) (AdminMeteringSourceTestResult, error)
}

type adminMeteringSourceUpsertRequestBody struct {
	SourceType            store.MeteringSourceType `json:"source_type"`
	EndpointURL           string                   `json:"endpoint_url"`
	AuthScheme            string                   `json:"auth_scheme,omitempty"`
	AuthReference         string                   `json:"auth_reference,omitempty"`
	CredentialValue       *string                  `json:"credential_value,omitempty"`
	ScrapeIntervalSeconds int                      `json:"scrape_interval_seconds,omitempty"`
	QueryIntervalSeconds  int                      `json:"query_interval_seconds,omitempty"`
	TimeoutSeconds        int                      `json:"timeout_seconds,omitempty"`
	Labels                map[string]string        `json:"labels,omitempty"`
	Enabled               bool                     `json:"enabled"`
}

type adminMeteringSourcePayload struct {
	ID                    string            `json:"id"`
	SourceKey             string            `json:"source_key"`
	SourceType            string            `json:"source_type"`
	EndpointURL           string            `json:"endpoint_url"`
	AuthScheme            string            `json:"auth_scheme"`
	AuthReference         string            `json:"auth_reference,omitempty"`
	CredentialSet         bool              `json:"credential_set"`
	ScrapeIntervalSeconds int               `json:"scrape_interval_seconds"`
	QueryIntervalSeconds  int               `json:"query_interval_seconds"`
	TimeoutSeconds        int               `json:"timeout_seconds"`
	Labels                map[string]string `json:"labels"`
	Enabled               bool              `json:"enabled"`
	Revision              int64             `json:"revision"`
	CreatedAt             string            `json:"created_at,omitempty"`
	UpdatedAt             string            `json:"updated_at,omitempty"`
}

func upsertAdminMeteringSourceHandler(manager AdminMeteringSourceManager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if manager == nil {
			apienvelope.WriteError(w, requestID(r), apierr.Internal(errNoAdminMeteringSourceManager))
			return
		}
		key := strings.TrimSpace(r.PathValue("source_key"))
		var body adminMeteringSourceUpsertRequestBody
		if err := validate.DecodeJSON(r.Body, &body, 0); err != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(err))
			return
		}
		in := AdminMeteringSourceUpsertInput{
			SourceType:            body.SourceType,
			EndpointURL:           body.EndpointURL,
			AuthScheme:            body.AuthScheme,
			AuthReference:         body.AuthReference,
			CredentialValue:       body.CredentialValue,
			ScrapeIntervalSeconds: body.ScrapeIntervalSeconds,
			QueryIntervalSeconds:  body.QueryIntervalSeconds,
			TimeoutSeconds:        body.TimeoutSeconds,
			Labels:                body.Labels,
			Enabled:               body.Enabled,
		}
		auditCtx, err := adminMeteringSourceAuditContext(r)
		if err != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(err))
			return
		}
		source, err := manager.UpsertMeteringSource(r.Context(), key, in, auditCtx)
		if err != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(err))
			return
		}
		apienvelope.WriteData(w, http.StatusOK, requestID(r), adminMeteringSourceResponse(source))
	}
}

func testAdminMeteringSourceHandler(manager AdminMeteringSourceManager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if manager == nil {
			apienvelope.WriteError(w, requestID(r), apierr.Internal(errNoAdminMeteringSourceManager))
			return
		}
		key := strings.TrimSpace(r.PathValue("source_key"))
		var body AdminMeteringSourceTestInput
		if err := validate.DecodeJSON(r.Body, &body, 0); err != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(err))
			return
		}
		auditCtx, err := adminMeteringSourceAuditContext(r)
		if err != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(err))
			return
		}
		result, err := manager.TestMeteringSource(r.Context(), key, body, auditCtx)
		if err != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(err))
			return
		}
		apienvelope.WriteData(w, http.StatusOK, requestID(r), result)
	}
}

func adminMeteringSourceAuditContext(r *http.Request) (store.AdminMeteringSourceAuditContext, error) {
	principal, ok := policy.PrincipalFromContext(r.Context())
	if !ok || principal.ID == "" || principal.OrganizationID == "" {
		return store.AdminMeteringSourceAuditContext{}, apierr.Unauthenticated("admin metering source operation requires an authenticated principal")
	}
	return store.AdminMeteringSourceAuditContext{
		ActorOrgID:    principal.OrganizationID,
		ActorID:       principal.ID,
		ActorKind:     principal.Kind.String(),
		RequestID:     telemetry.RequestID(r.Context()),
		CorrelationID: telemetry.CorrelationID(r.Context()),
	}, nil
}

func adminMeteringSourceResponse(source store.MeteringSource) adminMeteringSourcePayload {
	out := adminMeteringSourcePayload{
		ID:                    source.ID,
		SourceKey:             source.SourceKey,
		SourceType:            string(source.SourceType),
		EndpointURL:           source.EndpointURL,
		AuthScheme:            source.AuthScheme,
		AuthReference:         source.AuthReference,
		CredentialSet:         source.CredentialSet,
		ScrapeIntervalSeconds: source.ScrapeIntervalSeconds,
		QueryIntervalSeconds:  source.QueryIntervalSeconds,
		TimeoutSeconds:        source.TimeoutSeconds,
		Labels:                source.Labels,
		Enabled:               source.Enabled,
		Revision:              source.Revision,
	}
	if out.Labels == nil {
		out.Labels = map[string]string{}
	}
	if !source.CreatedAt.IsZero() {
		out.CreatedAt = source.CreatedAt.UTC().Format(time.RFC3339Nano)
	}
	if !source.UpdatedAt.IsZero() {
		out.UpdatedAt = source.UpdatedAt.UTC().Format(time.RFC3339Nano)
	}
	return out
}
