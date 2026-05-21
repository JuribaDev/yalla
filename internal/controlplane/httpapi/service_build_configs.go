package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/apienvelope"
	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
	"github.com/JuribaDev/yalla/internal/controlplane/policy"
	"github.com/JuribaDev/yalla/internal/controlplane/store"
	"github.com/JuribaDev/yalla/internal/controlplane/telemetry"
	"github.com/JuribaDev/yalla/internal/controlplane/validate"
)

var (
	errNoServiceBuildConfigReader = errors.New("httpapi: no service build config reader configured")
	errNoServiceBuildConfigSetter = errors.New("httpapi: no service build config setter configured")
)

// ServiceBuildConfigReader is the route dependency for build-config reads.
type ServiceBuildConfigReader interface {
	GetServiceBuildConfig(ctx context.Context, organizationID, serviceID string) (store.ServiceBuildConfig, error)
}

// ServiceBuildConfigSetter is the route dependency for build-config writes.
type ServiceBuildConfigSetter interface {
	SetServiceBuildConfig(ctx context.Context, in store.SetServiceBuildConfigInput) (store.ServiceBuildConfig, error)
}

type serviceBuildConfigWire struct {
	ServiceID  string          `json:"service_id"`
	BuildType  string          `json:"build_type"`
	SourceType string          `json:"source_type"`
	Source     json.RawMessage `json:"source"`
	Config     json.RawMessage `json:"config"`
	Version    int64           `json:"version"`
	CreatedAt  time.Time       `json:"created_at"`
	UpdatedAt  time.Time       `json:"updated_at"`
}

type serviceBuildConfigPayload struct {
	BuildConfig serviceBuildConfigWire `json:"build_config"`
}

type serviceBuildConfigRequest struct {
	BuildType  string          `json:"build_type"`
	SourceType string          `json:"source_type"`
	Source     json.RawMessage `json:"source"`
	Config     json.RawMessage `json:"config"`
}

func serviceBuildConfigOf(cfg store.ServiceBuildConfig) serviceBuildConfigWire {
	return serviceBuildConfigWire{
		ServiceID:  cfg.ServiceID,
		BuildType:  cfg.BuildType,
		SourceType: cfg.SourceType,
		Source:     cfg.SourceJSON,
		Config:     cfg.ConfigJSON,
		Version:    cfg.Version,
		CreatedAt:  cfg.CreatedAt,
		UpdatedAt:  cfg.UpdatedAt,
	}
}

func getServiceBuildConfigHandler(reader ServiceBuildConfigReader) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := policy.PrincipalFromContext(r.Context())
		if !ok || p.ID == "" {
			apienvelope.WriteError(w, requestID(r), apierr.Internal(errNoPrincipalOnContext))
			return
		}
		if reader == nil {
			apienvelope.WriteError(w, requestID(r), apierr.Internal(errNoServiceBuildConfigReader))
			return
		}
		cfg, err := reader.GetServiceBuildConfig(r.Context(), p.OrganizationID, r.PathValue("service_id"))
		if err != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(err))
			return
		}
		writeOrganizationETag(w, cfg.Version)
		apienvelope.WriteData(w, http.StatusOK, requestID(r), serviceBuildConfigPayload{BuildConfig: serviceBuildConfigOf(cfg)})
	}
}

func setServiceBuildConfigHandler(setter ServiceBuildConfigSetter) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := policy.PrincipalFromContext(r.Context())
		if !ok || p.ID == "" {
			apienvelope.WriteError(w, requestID(r), apierr.Internal(errNoPrincipalOnContext))
			return
		}
		if setter == nil {
			apienvelope.WriteError(w, requestID(r), apierr.Internal(errNoServiceBuildConfigSetter))
			return
		}
		ifMatchVersion, ifMatchErr := parseIfMatchVersion(r)
		if ifMatchErr != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(ifMatchErr))
			return
		}
		var req serviceBuildConfigRequest
		if err := validate.DecodeJSON(r.Body, &req, 0); err != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(err))
			return
		}
		correlation := telemetry.FromContext(r.Context())
		cfg, err := setter.SetServiceBuildConfig(r.Context(), store.SetServiceBuildConfigInput{
			OrganizationID: p.OrganizationID,
			ServiceID:      r.PathValue("service_id"),
			BuildConfig: store.ServiceBuildConfigInput{
				BuildType:  req.BuildType,
				SourceType: req.SourceType,
				SourceJSON: req.Source,
				ConfigJSON: req.Config,
			},
			IfMatchVersion: ifMatchVersion,
			ActorID:        p.ID,
			ActorKind:      string(p.Kind),
			ActorOrgID:     p.OrganizationID,
			RequestID:      correlation.RequestID,
			CorrelationID:  correlation.CorrelationID,
		})
		if err != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(err))
			return
		}
		writeOrganizationETag(w, cfg.Version)
		apienvelope.WriteData(w, http.StatusOK, requestID(r), serviceBuildConfigPayload{BuildConfig: serviceBuildConfigOf(cfg)})
	}
}
